package gateway

import "time"

const applicationTimezone = "Asia/Shanghai"

var applicationLocation = func() *time.Location {
	location, err := time.LoadLocation(applicationTimezone)
	if err != nil {
		return time.FixedZone(applicationTimezone, 8*60*60)
	}
	return location
}()

func inApplicationTimezone(value time.Time) time.Time {
	return value.In(applicationLocation)
}
