package mocks

import (
	"github.com/stretchr/testify/mock"
	"server-alpha/internal/interfaces"
)

type MockDatabaseMgr interface {
	GetPool() interfaces.PgxPoolIface
}

type MockDatabaseManager struct {
	mock.Mock
}

func (m *MockDatabaseManager) GetPool() interfaces.PgxPoolIface {
	args := m.Called()
	return args.Get(0).(interfaces.PgxPoolIface)
}
