import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { AccountService } from '../account.service';
import { UserService } from '../user.service';
import { User } from '../models/user';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialog, MatDialogRef } from '@angular/material/dialog';

@Component({

  selector: 'app-user-management',
  templateUrl: './user-management.component.html',
  styleUrls: ['./user-management.component.css']
})
export class UserManagementComponent implements OnInit{

  displayedColumns: string[] = ['id', 'email', 'firstName', 'lastName', 'emailConfirmed','action']; // columns for tablče
  dataSource: User[] = [];
  editUserForm!: FormGroup;

  @ViewChild('editDialog') editDialogTemplate!: TemplateRef<any>;

  constructor(private userService:UserService, private dialog:MatDialog, private fb:FormBuilder,private accountService:AccountService) { }

  ngOnInit(): void {
    this.getAllUsers();

    // Initialize the reactive form.
    this.editUserForm = this.fb.group({
      id: [{ value: null, disabled: true }],
      email: ['', [Validators.required, Validators.email]],
      firstName: ['', Validators.required],
      lastName: ['', Validators.required],
      emailConfirmed: [false]
    });
  }
  getAllUsers(){
    this.userService.getUsers().subscribe({
      next:(data)=>{
        this.dataSource = data;
      },
      error:(error)=>{
        console.error(error);
      }
    })
  }

  editUser(user: User): void {
    console.log('Editing user with id:', user.id);
    this.editUserForm.patchValue(user);
    // dialog 
    this.dialog.open(this.editDialogTemplate, { width: '500px' });
  }

  updateUser(): void {
    if (this.editUserForm.valid) {
      // Use getRawValue() to include the disabled 'id'
      const updatedUserFrom = this.editUserForm.getRawValue();
      
      // Create the DTO with property names matching the backend's UserDto
      const userDto = {
        Email: updatedUserFrom.email,       
        FirstName: updatedUserFrom.firstName,
        LastName: updatedUserFrom.lastName
      };
  
      // Call the update endpoint, passing the id from the form.
      this.userService.updateUser(updatedUserFrom.id, userDto).subscribe({
        next: () => {
          alert('User updated successfully');
          this.getAllUsers();
          this.dialog.closeAll();
        },
        error: (error) => {
          alert('Something went wrong');
          console.error(error);
        }
      });
  }
}


  deleteUser(user:any):void{
    this.userService.deleteUsers(user.id).subscribe({
      next:(data)=>{
        alert('User deleted successfully');
        this.getAllUsers();
      },
      error:(error)=>{
        alert('something went wrong');
        console.error(error);
      }
    })
  }
  reset2Fa(user:User){
    this.accountService.reset2Fa(user.id).subscribe({
      next: () => {
        alert(`2FA has been reset for ${user.email}.`);
      },
      error: err => {
        console.error(err);
        alert(`Failed to reset 2FA: ${err.error?.message || err.message}`);
      }
    });
  }
}
