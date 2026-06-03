package sla

import (
	"strings"
	"time"
)

const (
	StatusOnTrack     = "On Track"
	StatusApproaching = "Approaching"
	StatusOverdue     = "Overdue"

	approachingThresholdDays = 7
	kevDueDays               = 7
)

func DependentDueDays(severityLabel string) int {
	switch strings.ToUpper(severityLabel) {
	case "CRITICAL":
		return 20
	case "HIGH", "IMPORTANT":
		return 50
	case "MEDIUM", "MODERATE":
		return 80
	case "LOW":
		return 180
	default:
		return 0
	}
}

func CalculateDueDate(created time.Time, severityLabel string, kev bool) time.Time {
	if kev {
		return addBusinessDays(created, kevDueDays)
	}
	days := DependentDueDays(severityLabel)
	if days == 0 {
		return time.Time{}
	}
	return created.AddDate(0, 0, days)
}

func Status(dueDate time.Time) (string, int) {
	if dueDate.IsZero() {
		return "", 0
	}
	remaining := int(time.Until(dueDate).Hours()/24) + 1
	switch {
	case remaining < 0:
		return StatusOverdue, remaining
	case remaining <= approachingThresholdDays:
		return StatusApproaching, remaining
	default:
		return StatusOnTrack, remaining
	}
}

func IsKEV(labels []string) bool {
	for _, l := range labels {
		lower := strings.ToLower(l)
		if lower == "kev" || lower == "known-exploited-vulnerability" || strings.Contains(lower, "major-incident") {
			return true
		}
	}
	return false
}

func addBusinessDays(start time.Time, days int) time.Time {
	added := 0
	current := start
	for added < days {
		current = current.AddDate(0, 0, 1)
		wd := current.Weekday()
		if wd != time.Saturday && wd != time.Sunday {
			added++
		}
	}
	return current
}
