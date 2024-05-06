// Package mocks provides mock implementations for various interfaces to facilitate testing.
package mocks

import (
	"server-alpha/internal/interfaces"

	"github.com/stretchr/testify/mock"
)

// MockDatabaseMgr defines the interface for a mock of the database manager.
// It includes methods for interacting with the mock database connection pool.
type MockDatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
	GenerateCode(destDir string, schemaName string) error
	ClosePool() error
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

// GenerateCode simulates the behavior of generating code for the database schema.
// It returns an error if the operation fails.
func (m *MockDatabaseManager) GenerateCode(destDir string, schemaName string) error {
	args := m.Called(destDir, schemaName)
	return args.Error(0)
}

// ClosePool simulates the behavior of closing the database connection pool.
// It returns an error if the operation fails.
func (m *MockDatabaseManager) ClosePool() error {
	args := m.Called()
	return args.Error(0)
}
