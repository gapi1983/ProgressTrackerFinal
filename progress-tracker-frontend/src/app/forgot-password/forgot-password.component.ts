import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { AccountService } from '../account.service';

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.css']
})
export class ForgotPasswordComponent implements OnInit{
  

sendEmailForm : FormGroup = new FormGroup({});
submitted = false;

constructor(private route:ActivatedRoute, private accountService:AccountService,private fb: FormBuilder,private router: Router){}

  ngOnInit(): void {
    this.initializeForm();
  }

initializeForm(){
    this.sendEmailForm = this.fb.group({
      email: ['',[Validators.required, Validators.email]]
    });
  }

  sendEmail(){
    this.submitted = true;
    if(this.sendEmailForm.invalid){
      alert('Please enter a valid email');
    }
    const emailInput = this.sendEmailForm.value.email;

    this.accountService.forgotPassword(this.sendEmailForm.value.email).subscribe({
      next:(response:any)=>{
        alert('Check your email');
        this.router.navigateByUrl('/login');
      },
      error:(err)=>{
        alert('An error occurred, check the credentials');
      }
    })
  }
}
