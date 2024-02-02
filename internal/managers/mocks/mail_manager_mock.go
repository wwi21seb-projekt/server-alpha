package mocks

import "github.com/stretchr/testify/mock"

// MockMailManager is a mock of the MailManager.
// It implements methods to simulate the sending of activation and confirmation emails in tests.
type MockMailManager struct {
	mock.Mock
}

// SendActivationMail simulates the behavior of sending an activation email to the specified email address.
// It takes the recipient's email, username, the activation token, and the name of the service as parameters.
func (m *MockMailManager) SendActivationMail(email, username, token, serviceName string) error {
	args := m.Called(email, username, token, serviceName)
	return args.Error(0)
}

// SendConfirmationMail simulates the behavior of sending a confirmation email to the specified email address.
// It takes the recipient's email, username, and the name of the service as parameters.
func (m *MockMailManager) SendConfirmationMail(email, username, serviceName string) error {
	args := m.Called(email, username, serviceName)
	return args.Error(0)
}
