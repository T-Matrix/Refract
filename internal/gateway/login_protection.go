package gateway

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	loginFailureLimit       = 5
	loginFailureWindow      = 15 * time.Minute
	loginBlockDuration      = 24 * time.Hour
	loginAttemptRecordLimit = 10000
)

type loginAttemptState struct {
	Failures     int
	FirstFailure int64
	BlockedUntil int64
	LastSeen     int64
}

func (s *telemetryStore) loginRetryAfter(ctx context.Context, clientIP string, now time.Time) (time.Duration, error) {
	var state loginAttemptState
	err := s.db.QueryRowContext(ctx,
		`SELECT failures,first_failure,blocked_until,last_seen FROM admin_login_attempts WHERE client_ip=?`,
		clientIP,
	).Scan(&state.Failures, &state.FirstFailure, &state.BlockedUntil, &state.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	nowUnix := now.Unix()
	if state.BlockedUntil > nowUnix {
		return time.Duration(state.BlockedUntil-nowUnix) * time.Second, nil
	}
	if state.FirstFailure+int64(loginFailureWindow/time.Second) <= nowUnix {
		_, err = s.db.ExecContext(ctx, `DELETE FROM admin_login_attempts WHERE client_ip=?`, clientIP)
		return 0, err
	}
	return 0, nil
}

func (s *telemetryStore) recordLoginFailure(ctx context.Context, clientIP string, now time.Time) (time.Duration, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	nowUnix := now.Unix()
	windowStart := now.Add(-loginFailureWindow).Unix()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM admin_login_attempts WHERE blocked_until<=? AND first_failure<=?`, nowUnix, windowStart,
	); err != nil {
		return 0, err
	}

	var state loginAttemptState
	err = tx.QueryRowContext(ctx,
		`SELECT failures,first_failure,blocked_until,last_seen FROM admin_login_attempts WHERE client_ip=?`,
		clientIP,
	).Scan(&state.Failures, &state.FirstFailure, &state.BlockedUntil, &state.LastSeen)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err == nil && state.BlockedUntil > nowUnix {
		return time.Duration(state.BlockedUntil-nowUnix) * time.Second, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_login_attempts`).Scan(&count); err != nil {
			return 0, err
		}
		if count >= loginAttemptRecordLimit {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM admin_login_attempts WHERE client_ip=(SELECT client_ip FROM admin_login_attempts ORDER BY last_seen ASC LIMIT 1)`,
			); err != nil {
				return 0, err
			}
		}
		state.FirstFailure = nowUnix
	}

	state.Failures++
	state.LastSeen = nowUnix
	if state.Failures >= loginFailureLimit {
		state.BlockedUntil = now.Add(loginBlockDuration).Unix()
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO admin_login_attempts(client_ip,failures,first_failure,blocked_until,last_seen) VALUES(?,?,?,?,?)
		 ON CONFLICT(client_ip) DO UPDATE SET failures=excluded.failures,first_failure=excluded.first_failure,blocked_until=excluded.blocked_until,last_seen=excluded.last_seen`,
		clientIP, state.Failures, state.FirstFailure, state.BlockedUntil, state.LastSeen,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if state.BlockedUntil > nowUnix {
		return time.Duration(state.BlockedUntil-nowUnix) * time.Second, nil
	}
	return 0, nil
}

func (s *telemetryStore) resetLoginFailures(ctx context.Context, clientIP string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_login_attempts WHERE client_ip=?`, clientIP)
	return err
}
