import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { UserService } from '../user.service';
import { TaskService } from '../task.service';
import { User } from '../models/user';


@Component({
  selector: 'app-create-task',
  templateUrl: './create-task.component.html',
  styleUrls: ['./create-task.component.css']
})
export class CreateTaskComponent implements OnInit {

  taskForm!:FormGroup;
  userList: User[] = [];

  constructor(private fb:FormBuilder, private taskService:TaskService, private userService:UserService) { }

  ngOnInit(): void {
    this.taskForm = this.fb.group({
      title: ['', [Validators.required, Validators.maxLength(100)]],
      description: ['', Validators.required],
      dueDate: ['', Validators.required],
      status: ['In Progress'],
      progressPercentage: [0, [Validators.required, Validators.min(0), Validators.max(100)]],
      assignedToUserId: ['', Validators.required]
    });

    this.userService.getUsers().subscribe({
      next: (allUsers) => {
        //  Keep only employees and managers
        this.userList = allUsers.filter(user => {
          // user.role might be an array like ['Admin','Manager'] or ['Employee']
          return user.role.includes('Manager') || user.role.includes('Employee');
        });
      },
      error: (error) => {
        console.error(error);
      }
    });
  }

  onSubmit() {
    if (this.taskForm.valid) {
      const formValue = this.taskForm.value;
  
      // Convert the picked Date into an ISO string:
      const isoDueDate = new Date(formValue.dueDate).toISOString();
  
      const createTaskDto = {
        title: formValue.title,
        description: formValue.description,
        dueDate: new Date(formValue.dueDate).toISOString(),  
        status: formValue.status,
        progressPercentage: formValue.progressPercentage,
        assignedToUserId: formValue.assignedToUserId
      };
  
      this.taskService.createTask(createTaskDto).subscribe({
        next: response => {
          alert('Task created successfully:');
          this.taskForm.reset();
        },
        error: error => {
          console.log('Error creating task:', error);
        }
      });
    }
  }
}