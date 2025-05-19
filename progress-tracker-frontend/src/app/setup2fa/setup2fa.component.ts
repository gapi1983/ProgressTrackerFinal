import { Component } from '@angular/core';
import { AccountService } from '../account.service';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';

@Component({
  selector: 'app-setup2fa',
  templateUrl: './setup2fa.component.html',
  styleUrls: ['./setup2fa.component.css']
})
export class Setup2faComponent {
  qrUri      = '';
  encodedUri = ''; 
  sharedKey  = '';
  form!: FormGroup;
  backendErr = '';

  constructor(private acc: AccountService,
              private fb: FormBuilder,
              private router: Router) {}

  ngOnInit(): void {
    this.form = this.fb.group({
      code: ['', [Validators.required, Validators.pattern(/^\d{6}$/)]]
    });

    // fetch QR data
    this.acc.get2FaSetup().subscribe({
      next: d => {
        this.qrUri    = d.authenticatorUri;     // <- contains otpauth://…
        this.sharedKey = d.sharedKey;
      },
      error: () => this.backendErr = 'Could not load 2‑FA data'
    });
  }

  confirm(): void {
    if (this.form.invalid) { return; }

    this.backendErr = '';
    const code = this.form.value.code;

    this.acc.enable2fa(code).subscribe({
      next: () => {
        // 2FA is now enabled — send them back to the login screen
        this.router.navigateByUrl('/login');
        alert('2FA is now enabled, please login');
        },
      error: err => this.backendErr = err?.error ?? 'Invalid code'
    });
  }
  urlEncode(v: string): string {
    return encodeURIComponent(v);
  }
}
