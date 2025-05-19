import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AccountService } from 'src/app/account.service';

@Component({
  selector: 'app-user-dashboard',
  templateUrl: './user-dashboard.component.html',
  styleUrls: ['./user-dashboard.component.css']
})
export class UserDashboardComponent{

  constructor(private router:Router, public accountService: AccountService) { }

  logout(){
    this.accountService.logout().subscribe({
      next:(res:any)=>{
        this.router.navigateByUrl('/login');
        alert("Logged out successfully");
      },
      error:(err)=>{
        alert("Something went wrong");
      }
    })
  }
}
