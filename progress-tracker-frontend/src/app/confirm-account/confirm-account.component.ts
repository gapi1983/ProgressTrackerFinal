import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Route, Router } from '@angular/router';
import { AccountService } from '../account.service';

@Component({
  selector: 'app-confirm-account',
  templateUrl: './confirm-account.component.html',
  styleUrls: ['./confirm-account.component.css']
})
export class ConfirmAccountComponent implements OnInit {

  constructor(private route:ActivatedRoute, private accountService:AccountService, private router:Router) { }

  ngOnInit(): void {
    this.route.queryParams.subscribe(params=>{
      const email = params["email"] || "";
      const token = params["token"] || "";

      if(!email || !token){
        // if in url either parameter is missing show error
        alert("Invalid URL parameters");
        return;
      }

      this.accountService.confirmEmail(email, token).subscribe({
        next:()=>{
          alert("Account confirmed successfully");
          this.router.navigate(['/login']);
        },
        error:()=>{
          alert("Something went wrong");
        }
      })
    });
  }

}
