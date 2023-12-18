package utils

import (
	"github.com/go-playground/validator/v10"
	"github.com/truemail-rb/truemail-go"
	"regexp"
	"sync"
	"unicode"
)

type Validator struct {
	Validate    *validator.Validate
	VerifyEmail func(email string) bool
}

var instance *Validator
var configuration *truemail.Configuration

func GetValidator() *Validator {
	once := sync.Once{}
	once.Do(func() {
		configuration, _ = truemail.NewConfiguration(truemail.ConfigurationAttr{
			VerifierEmail:         "team@mail.server-alpha.tech",
			ValidationTypeDefault: "mx",
			SmtpFailFast:          true,
		})

		instance = &Validator{
			Validate:    validator.New(validator.WithRequiredStructEnabled()),
			VerifyEmail: validateEmail,
		}

		registerCustomValidators(instance.Validate)
	})

	return instance
}

func validateEmail(email string) bool {
	return truemail.IsValid(email, configuration)
}

func registerCustomValidators(v *validator.Validate) {
	err := v.RegisterValidation("username_validation", usernameValidation)
	if err != nil {
		return
	}

	err = v.RegisterValidation("password_validation", passwordValidation)
	if err != nil {
		return
	}
}

func usernameValidation(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	// Define the regular expression pattern for a valid username
	// The pattern allows a-z, A-Z, 0-9, ., -, and _
	pattern := `^[a-zA-Z0-9.\-_]+$`
	match, err := regexp.MatchString(pattern, username)
	if err != nil {
		return false
	}

	return match
}

func passwordValidation(fl validator.FieldLevel) bool {
	var upperLetter, lowerLetter, number, specialChar bool

	value := fl.Field().String()
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}

		switch {
		case unicode.IsUpper(r):
			upperLetter = true
		case unicode.IsLower(r):
			lowerLetter = true
		case unicode.IsNumber(r):
			number = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			specialChar = true
		}
	}

	return upperLetter && lowerLetter && number && specialChar
}
