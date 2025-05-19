import { Component, OnInit } from '@angular/core';
import { AccountService } from '../account.service';
import { Form, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit{

  registerForm : FormGroup = new FormGroup({});
  submitted = false;
  errors:string[] = [];

constructor(private accountService:AccountService, private formBuilder:FormBuilder, private router: Router) { }

  ngOnInit(): void {
    this.initializeForm();
  }

  initializeForm() {
  this.registerForm = this.formBuilder.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required, Validators.minLength(8), Validators.maxLength(16)]],
    confirmPassword: ['', [Validators.required]], 
    firstName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(16)]], 
    lastName: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(16)]], 
  });
  }

  register(){
    this.submitted = true;
    if(this.registerForm.valid){
      this.accountService.register(this.registerForm.value).subscribe({
        next:(response)=>{
          this.router.navigateByUrl('/login');
          alert("Registration successful, please login");
        },
        error:(err)=>{
          this.errors = err.error;
          alert("something went wrong, check the credentials");
        }
      })
    }
    
  }

}
