using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using FluentValidation;

namespace AspNetBase.Models
{
    public class ExternalLoginConfirmationViewModel
    {
        [Display(Name = "Email")]
        public string Email { get; set; }
    }

    public class ExternalLoginConfirmationViewModelValidator : AbstractValidator<ExternalLoginConfirmationViewModel>
    {
        public ExternalLoginConfirmationViewModelValidator()
        {
            RuleFor(c => c.Email).EmailAddress().NotEmpty();
        }
    }

    public class ExternalLoginListViewModel
    {
        public string Action { get; set; }
        public string ReturnUrl { get; set; }
    }

    public class ManageUserViewModel
    {
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public string OldPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        public string ConfirmPassword { get; set; }
    }

    public class ManageUserViewModelValidator : AbstractValidator<ManageUserViewModel>
    {
        public ManageUserViewModelValidator()
        {
            RuleFor(c => c.OldPassword).NotEmpty();
            RuleFor(c => c.NewPassword).Length(6, 100).NotEmpty();
            RuleFor(c => c.ConfirmPassword).Equal(c => c.NewPassword).WithMessage("The new password and confirmation password do not match.");
        }
    }

    public class LoginViewModel
    {
        [Display(Name = "Email")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
    public class LoginViewModelValidator : AbstractValidator<LoginViewModel>
    {
        public LoginViewModelValidator()
        {
            RuleFor(c => c.Email).EmailAddress().NotEmpty();
            RuleFor(c => c.Password).NotEmpty();
        }
    }

    public class RegisterViewModel
    {
        [Display(Name = "Name")]
        public string Name { get; set; }

        [Display(Name = "Email")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        public string ConfirmPassword { get; set; }
    }

    public class RegisterViewModelValidator : AbstractValidator<RegisterViewModel>
    {
        public RegisterViewModelValidator()
        {
            RuleFor(c => c.Name).NotEmpty();
            RuleFor(c => c.Email).EmailAddress().NotEmpty();
            RuleFor(c => c.Password).Length(6, 100).NotEmpty();
            RuleFor(c => c.ConfirmPassword).Equal(c => c.Password).WithMessage("The password and confirmation password do not match.");
        }
    }

    public class ResetPasswordViewModel
    {
        [Display(Name = "Email")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }
    public class ResetPasswordViewModelValidator : AbstractValidator<ResetPasswordViewModel>
    {
        public ResetPasswordViewModelValidator()
        {
            RuleFor(c => c.Email).EmailAddress().NotEmpty();
            RuleFor(c => c.Password).Length(6, 100).NotEmpty();
            RuleFor(c => c.ConfirmPassword).Equal(c => c.Password).WithMessage("The password and confirmation password do not match.");
        }
    }

    public class ForgotPasswordViewModel
    {
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
    public class ForgotPasswordViewModelValidator : AbstractValidator<ForgotPasswordViewModel>
    {
        public ForgotPasswordViewModelValidator()
        {
            RuleFor(c => c.Email).EmailAddress().NotEmpty();
        }
    }

    public class EditProfileViewModel
    {
        
    }

    public class ChangeEmailViewModel
    {
        public string NewEmail { get; set; }

        public string Password { get; set; }
    }
}