//go:build linux

package faketcp

import "time"

// GetExpire returns the current flow expiration duration (for testing).
func GetExpire() time.Duration {
	return expire
}

// SetExpire sets the flow expiration duration (for testing).
func SetExpire(d time.Duration) {
	expire = d
}

// FlowCount returns the number of entries in the flow table (for testing).
func FlowCount(conn *FakeTCPPacketConn) int {
	count := 0
	conn.flowTable.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// CleanExpiredFlows manually triggers the flow cleanup logic (for testing).
func CleanExpiredFlows(conn *FakeTCPPacketConn) {
	conn.flowTable.Range(func(key, value any) bool {
		v := value.(*tcpFlow)
		if time.Since(time.Unix(0, v.ts.Load())) > expire {
			c := v.conn.Load()
			if c != nil {
				setTTL(c, 64)
				c.Close()
			}
			conn.flowTable.Delete(key)
		}
		return true
	})
}
