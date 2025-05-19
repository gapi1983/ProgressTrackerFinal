import { Component, OnInit } from '@angular/core';
import {ChangeDetectionStrategy} from '@angular/core';
import {MatButtonModule} from '@angular/material/button';
import {MatCardModule} from '@angular/material/card';
import { Router } from '@angular/router';
import { AccountService } from '../account.service';
import { Form, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { LoginResponse } from '../models/loginResponse';


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
  
})
export class LoginComponent implements OnInit	{

  loginForm : FormGroup = new FormGroup({});
  twoFaForm!: FormGroup;
  submitted = false;
  show2Fa = false; 
  backendError = '';
  pendingUserId: string = ''

  

  constructor(private router:Router, private accountService: AccountService, private formBuilder:FormBuilder) { }

  ngOnInit(): void {
    this.initializeForm();

  }

  initializeForm() {
    this.loginForm = this.formBuilder.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8), Validators.maxLength(16)]],
    });
    this.twoFaForm = this.formBuilder.group({
      code:["",[Validators.required, Validators.pattern(/^\d{6}$/)]],
    })
  }

  submitLogin(): void {
    if (this.loginForm.invalid) { return; }
  
    this.backendError = '';
  
    this.accountService.login(this.loginForm.value).subscribe({
      next: (res) => {
  
        if (res.mustSetup2FA) {         
          console.log("setup route")        // ← first‑time user
          this.router.navigateByUrl('/setup-2fa');
          return;
        }
  
        if (res.requires2FA) {                // ← 2‑FA required
          // save userId for the next call
          this.pendingUserId = res.userId!;
          this.show2Fa = true;
  return;
        }
  
        this.finishLogin();                     // ← no 2‑FA needed (old users only)
      },
      error: err => this.backendError = err.error || 'Login failed'
    });
  }

  submit2Fa(): void {
    if (this.twoFaForm.invalid) { return; }
    const { code} = this.twoFaForm.value;
    const payload = {
      userId: this.pendingUserId,
      code
    };
    this.accountService.login2fa(payload).subscribe({
      next : ()  => this.finishLogin(),
      error: err => this.backendError = err?.error ?? 'Invalid 2‑FA code'
    });
  }

  private finishLogin(): void {
    this.accountService.getCurrentUser().subscribe({
      next : () => this.router.navigateByUrl('/user-dashboard'),
      error: () => this.router.navigateByUrl('/user-dashboard')
    });
  }
}
