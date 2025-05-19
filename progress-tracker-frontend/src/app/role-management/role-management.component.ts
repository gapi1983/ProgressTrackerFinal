import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { UserService } from '../user.service';
import { MatDialog } from '@angular/material/dialog';
import { FormBuilder, FormGroup } from '@angular/forms';
import { User } from '../models/user';
import { Role } from '../models/role';
import { ResolveStart } from '@angular/router';

@Component({
  selector: 'app-role-management',
  templateUrl: './role-management.component.html',
  styleUrls: ['./role-management.component.css']
})
export class RoleManagementComponent implements OnInit{

  @ViewChild('editRoleDialog') editRoleDialog!: TemplateRef<any>;
  @ViewChild('viewUsersWithThisRoleDialog') viewUsersWithThisRoleDialog!: TemplateRef<any>;

displayedColumns: string[] = ['roleId','roleName','action']; // columns 
dataSource: Role[] = [];
selectedRole?: Role;
usersWithRole: User[] = [];
userEmail: string = '';

 constructor(private userService:UserService, private dialog:MatDialog, private fb:FormBuilder) { }

 ngOnInit(): void {
  this.userService.getAllRoles().subscribe({
    next: (roles) => {
      this.dataSource = roles; 
    },
    error: (error) => {
      console.error(error);
    }
  });
}

addRoleToUser(email: string): void {
  if (!this.selectedRole) {
    console.error('No role selected');
    return;
  }
  this.userService.getUserByEmail(email).subscribe({
    next:(user)=>{
      this.userService.addRoleToUser(user.id, this.selectedRole!.roleName).subscribe({
        next: () => {
          this.refreshUsersInRole();
          this.userEmail = "";
        },
        error: (err) => console.error(err)
      });
    }
  })
}

removeRoleFromUser(email:string){
  if(!this.selectedRole){
    console.error('No role selected');
    return;
  }
  this.userService.getUserByEmail(email).subscribe({
    next:(user)=>{
      this.userService.removeRoleFromUser(user.id, this.selectedRole!.roleName).subscribe({
        next:()=>{
          this.refreshUsersInRole();
          this.userEmail = "";
        },
        error:(err)=>console.error(err)
      });
    }
  });
}

refreshUsersInRole(): void {
  // Refresh the list of users assigned to the selected role
  if (this.selectedRole) {
    this.userService.getUsersByRole(this.selectedRole.id).subscribe({
      next: (users) => {
        this.usersWithRole = users;
      },
      error: (err) => console.error(err)
    });
  }
}
  
viewUsersWithThisRole(role: Role) {
  this.selectedRole = role;
  this.userService.getUsersByRole(role.id).subscribe({
    next: (users) => {
      this.usersWithRole = users;
    },
    error: (error) => {
      console.error(error);
      this.usersWithRole = [];
    }
  });
  this.dialog.open(this.viewUsersWithThisRoleDialog);
}



}
