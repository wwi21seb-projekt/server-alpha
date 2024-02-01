package utils

import (
	"github.com/go-playground/validator/v10"
	"github.com/truemail-rb/truemail-go"
	"regexp"
	"server-alpha/internal/schemas"
	"sync"
	"unicode"
	"unicode/utf8"
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
	_ = v.RegisterValidation("username_validation", usernameValidation)
	_ = v.RegisterValidation("password_validation", passwordValidation)
	_ = v.RegisterValidation("post_validation", postValidation)
	_ = v.RegisterValidation("location_validation", locationValidation)
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

func postValidation(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return utf8.ValidString(value)
}

func locationValidation(fl validator.FieldLevel) bool {
	// Get the location struct from the field
	location := fl.Field().Interface().(schemas.LocationDTO)

	// If location is empty, return true since it is not required
	if location == (schemas.LocationDTO{}) {
		return true
	}

	// Check if the longitude is valid
	if location.Longitude < -180 || location.Longitude > 180 {
		return false
	}

	// Check if the latitude is valid
	if location.Latitude < -90 || location.Latitude > 90 {
		return false
	}

	// Check if the accuracy is valid
	if location.Accuracy < 0 {
		return false
	}

	return true
}
