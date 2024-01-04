package mocks

import "github.com/stretchr/testify/mock"

type MockMailManager struct {
	mock.Mock
}

func (m *MockMailManager) SendActivationMail(email, username, token, serviceName string) error {
	args := m.Called(email, username, token, serviceName)
	return args.Error(0)
}

func (m *MockMailManager) SendConfirmationMail(email, username, serviceName string) error {
	args := m.Called(email, username, serviceName)
	return args.Error(0)
}
