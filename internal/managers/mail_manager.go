// Package managers handles the sending of emails for account activation and confirmation using the Mailgun service
// and the Hermes package for email formatting.
package managers

import (
	"context"
	"fmt"
	"github.com/mailgun/mailgun-go/v4"
	"github.com/matcornic/hermes/v2"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

// MailMgr is an interface that outlines the contract for email management.
// It includes methods for sending activation and confirmation emails.
type MailMgr interface {
	SendActivationMail(email, username, token, serviceName string) error
	SendConfirmationMail(email, username, serviceName string) error
}

// MailManager is a concrete implementation of the MailMgr interface.
// It uses the Mailgun service for sending emails and the Hermes package for formatting emails.
type MailManager struct {
	Hermes  *hermes.Hermes
	Mailgun *mailgun.MailgunImpl
}

var from = "Server Alpha <team@mail.server-alpha.tech>"
var environment string

// SendActivationMail sends an activation email to a user with a token to activate their account.
// The email content is formatted using the Hermes package and sent using the Mailgun service.
func (mm *MailManager) SendActivationMail(email, username, token, serviceName string) error {
	if environment != "production" {
		log.Info("Skipping confirmation mail in development mode")
		return nil
	}
	mailBody := hermes.Email{
		Body: hermes.Body{
			Name: username,
			Intros: []string{
				fmt.Sprintf("Welcome to %s! We're very excited to have you on board.", serviceName),
				"Please note that the registration is completed by Server Alpha. If you have any questions, feel free to reach out to us at any time via team@mail.server-alpha.tech.",
			},
			Outros: []string{
				fmt.Sprintf("We thank you again for choosing %s in combination with Server Alpha!", serviceName),
			},
			Actions: []hermes.Action{
				{
					Instructions: fmt.Sprintf("To activate your account, please login to %s and enter the following code:", serviceName),
					InviteCode:   token,
				},
			},
		},
	}

	emailBody, err := mm.Hermes.GenerateHTML(mailBody)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	message := mm.Mailgun.NewMessage(from, "Activate your account", "", email)
	message.SetHtml(emailBody)
	_, _, err = mm.Mailgun.Send(ctx, message)
	if err != nil {
		log.Warning("Error sending activation mail: " + err.Error())
		return err
	}
	log.Debug("Activation mail sent to ", email)

	return nil
}

// SendConfirmationMail sends a confirmation email to a user to confirm that their account has been activated.
// The email content is formatted using the Hermes package and sent using the Mailgun service.
func (mm *MailManager) SendConfirmationMail(email, username, serviceName string) error {
	if environment != "production" {
		log.Info("Skipping confirmation mail in development mode")
		return nil
	}

	mailBody := hermes.Email{
		Body: hermes.Body{
			Name: username,
			Intros: []string{
				"Your account has been successfully activated!",
				"Please note that the registration is completed by Server Alpha.",
				"If you have any questions, feel free to reach out to us at any time via team@mail.server-alpha.tech.",
			},
			Outros: []string{
				fmt.Sprintf("Have fun using %s! We'll be happy to help you in your adventures.", serviceName),
			},
		},
	}

	emailBody, err := mm.Hermes.GenerateHTML(mailBody)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer func() {
		if err := ctx.Err(); err != nil {
			log.Debug("Context error: ", err)
		}
		cancel()
		log.Debug("Context canceled")
	}()

	message := mm.Mailgun.NewMessage(from, "Account successfully activated", emailBody, email)
	_, _, err = mm.Mailgun.Send(ctx, message)
	if err != nil {
		log.Warning("Error sending confirmation mail: " + err.Error())
		return err
	}
	log.Debug("Confirmation mail sent to ", email)

	return nil
}

// NewMailManager initializes a new MailManager instance with configured Mailgun and Hermes settings.
// It also checks the runtime environment to determine if emails should be sent.
// This function is used during the initialization phase of the application.
func NewMailManager() MailMgr {
	log.Info("Initializing mail manager")
	// Check if running in production
	environment = os.Getenv("ENVIRONMENT")

	if environment != "production" {
		log.Println("Running in development mode, email will not be sent to users")
	}

	apiKey := os.Getenv("MAILGUN_API_KEY")
	mailgunInstance := mailgun.NewMailgun("mail.server-alpha.tech", apiKey)
	mailgunInstance.SetAPIBase(mailgun.APIBaseEU)

	mm := &MailManager{
		Hermes: &hermes.Hermes{
			Theme:         new(hermes.Default),
			TextDirection: hermes.TDLeftToRight,
			Product: hermes.Product{
				Name:        "Server Alpha",
				Link:        "https://server-alpha.com/",
				Logo:        "https://wallpapercave.com/wp/wp8802810.jpg",
				Copyright:   "© WWI21SEB / Projektkonzeption und Realisierung",
				TroubleText: "If you’re having trouble with the button '{ACTION}', copy and paste the URL below into your web browser.",
			},
		},
		Mailgun: mailgunInstance,
	}
	log.Info("Initialized mail manager")
	return mm
}
