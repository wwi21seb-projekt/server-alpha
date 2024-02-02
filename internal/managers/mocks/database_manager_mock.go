// Package mocks provides mock implementations for various interfaces to facilitate testing.
package mocks

import (
	"github.com/stretchr/testify/mock"
	"server-alpha/internal/interfaces"
)

// MockDatabaseMgr defines the interface for a mock of the database manager.
// It includes methods for interacting with the mock database connection pool.
type MockDatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
}

// MockDatabaseManager is a mock of the DatabaseManager.
// It implements MockDatabaseMgr and is used to simulate database operations in tests.
type MockDatabaseManager struct {
	mock.Mock
}

// GetPool returns a mock of the database connection pool.
// It simulates the behavior of retrieving a database connection pool in tests.
func (m *MockDatabaseManager) GetPool() interfaces.PgxPoolIface {
	args := m.Called()
	return args.Get(0).(interfaces.PgxPoolIface)
}
