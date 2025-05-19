import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { RoleManagementComponent } from './role-management.component';
import { MatTableModule } from '@angular/material/table';
import { MatDialogModule } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule, MatCardTitle } from '@angular/material/card';
import { MatListModule } from '@angular/material/list';
import { MatSelectModule } from '@angular/material/select';



const routes: Routes = [
  {path:'', component:RoleManagementComponent}
]

@NgModule({
  declarations: [RoleManagementComponent],
  imports: [
    CommonModule,
        MatTableModule,
        MatDialogModule,
        FormsModule,
        MatIconModule,
        MatListModule,
        MatFormFieldModule,
        MatInputModule,
        MatSelectModule,
        MatCardModule,
        MatCheckboxModule,
        ReactiveFormsModule,
        MatButtonModule,
    RouterModule.forChild(routes)
  ]
})
export class RoleManagementModule { }
