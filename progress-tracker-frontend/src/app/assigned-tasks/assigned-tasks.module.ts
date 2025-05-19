import { NgModule, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { AssignedTasksComponent } from './assigned-tasks.component';

import { TaskService } from '../task.service';
import { TaskItem } from '../models/taskItem';
import { MatCardModule } from '@angular/material/card';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { MatOptionModule } from '@angular/material/core';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';


const routes: Routes = [
  {path:'', component:AssignedTasksComponent}
]

@NgModule({
  declarations: [AssignedTasksComponent],
  imports: [
    CommonModule,
    RouterModule.forChild(routes),
    MatCardModule,
    MatProgressBarModule,
    MatProgressBarModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatButtonModule,
    MatOptionModule,
    FormsModule,
    MatIconModule

  ]
})
export class AssignedTasksModule implements OnInit{
  tasks:TaskItem[] = [];

  constructor(private taskService: TaskService) { }

  ngOnInit(): void {
    this.taskService.getAllTasks().subscribe({
      next: (data) => this.tasks = data,
      error: (error) => console.error('Error fetching tasks:', error),
    })
  }
}
