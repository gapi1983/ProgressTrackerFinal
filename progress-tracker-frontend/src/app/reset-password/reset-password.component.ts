import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AccountService } from '../account.service';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.css']
})
export class ResetPasswordComponent implements OnInit{

  resetPasswordForm : FormGroup = new FormGroup({});
  submitted = false;


  token: string = '';
  email: string = '';

  constructor(private route:ActivatedRoute, private accountService:AccountService,private fb: FormBuilder,private router: Router){}


  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.email = params['email'] || '';
      this.token = params['token'] || '';
    });
    this.initializeForm();
  }

  initializeForm(){
    this.resetPasswordForm = this.fb.group({
      newPassword: ['', [Validators.required, Validators.minLength(8), Validators.maxLength(16)]],
      confirmPassword: ['', [Validators.required]]
    });
  }

  resetPassword(){
    this.submitted = true;
    if(this.resetPasswordForm.valid){
      const newPassword = this.resetPasswordForm.value.newPassword;
      const confirmPassword = this.resetPasswordForm.value.confirmPassword;

      const body ={
      email: this.email,
      token: this.token,
      newPassword: newPassword,
      confirmPassword: confirmPassword
      };
      this.accountService.resetPassword(body).subscribe({
        next:(response)=>{
          alert('Password reset successfully');
          this.router.navigateByUrl('/login');
        },
        error:(err)=>{
          alert('An error occurred, check the credentials');
        }
      })
  }
}}
  
