import { Component, OnInit } from '@angular/core';
import { UserService } from '../user.service';
import { TaskService } from '../task.service';
import { Observable } from 'rxjs';
import { UpdateTask } from '../models/updateTask';
import { AccountService } from '../account.service';
import { CommentService } from '../comment.service';
import { AppComment } from '../models/appComment';
import { CreateComment } from '../models/createComment';

@Component({
  selector: 'app-assigned-tasks',
  templateUrl: './assigned-tasks.component.html',
  styleUrls: ['./assigned-tasks.component.css']
})
export class AssignedTasksComponent implements OnInit {
  constructor(private userService:UserService, private taskService:TaskService, private accountSevice:AccountService, private commentService:CommentService) { }
  tasks: any[] = [];
  roles: string[] = [];
  isEmployee = false;
  showComments = false;
  comments: AppComment[] = []; // for testing
  newComment: string = '';
  currentUserId: string = '';




  ngOnInit(): void {
    this.accountSevice.getCurrentUser().subscribe({
      next:(user)=>{
        // storing roles and id
        this.roles = user.roles || [];
        this.currentUserId = user.id;
        // Check if the user is an employee


        this.isEmployee = this.roles.includes('Employee');
        if (this.isEmployee) {
          this.taskService.getMyTasks().subscribe({
            next:(tasks)=>{
              this.tasks = tasks;
            },
            error:(error)=>{
              console.error('Error fetching employees tasks:', error);
            }
          })
        }
        else{
          this.taskService.getAllTasks().subscribe({
            next:(tasks)=>{
              this.tasks = tasks;
            },
            error:(error)=>{
              console.error('Error fetching tasks:', error);
            }
          })
        }
        },
    error:(error)=>{
      console.error('Error fetching current user:', error);
    }
    })
    }

    canDelete(): boolean {
      return this.roles.includes('Manager');
    }

selectedTask: any = null;
isModalOpen: boolean = false;

onTaskClick(task: any) {
  this.selectedTask = { ...task }; // clone to avoid live editing
  this.isModalOpen = true;
  this.commentService.getCommentsForTask(task.taskId).subscribe({
    next: (comments) => {
      this.comments = comments;
      console.log('Comments fetched successfully:', comments);
    },
    error: (error) => {
      console.error('Error fetching comments:', error);
    }
  });
}

closeModal() {
  this.isModalOpen = false;
  this.selectedTask = null;
  this.newComment = '';
}
toggleComments() {
  this.showComments = !this.showComments;
}

deleteTask(taskId: string): void {
  this.taskService.deleteTask(taskId).subscribe({
    next: () => {
      console.log('Task deleted successfully');
      // Update local list
      this.tasks = this.tasks.filter(task => task.taskId !== taskId);
    },
    error: (error) => {
      console.error('Error deleting task:', error);
    }
  });
}



updateTask(): void {
  if (!this.selectedTask) return;

  // Create payload matching UpdateTask model
  const updatePayload: UpdateTask = {
    title: this.selectedTask.title,
    description: this.selectedTask.description,
    dueDate: this.selectedTask.dueDate,
    status: this.selectedTask.status,
    progressPercentage: this.selectedTask.progressPercentage,
    assignedToUserId: this.selectedTask.assignedToUserId
  };

  this.taskService.updateTask(this.selectedTask.taskId, updatePayload).subscribe({
    next: (data) => {
      console.log('Task updated successfully:', data);

      // Update local list 
      const index = this.tasks.findIndex(t => t.taskId === this.selectedTask?.taskId);
      if (index !== -1) this.tasks[index] = { ...this.selectedTask };

      this.closeModal();
    },
    error: (error) => {
      console.error('Error updating task:', error);
    }
  });
}

submitComment() {
  const text = this.newComment.trim()
  if (!text) {
    alert('Comment cannot be empty');
    return;
  }
  const commentContent: CreateComment = {
    userId: this.currentUserId,
    content: text,
  };
  this.commentService.createComment(this.selectedTask.taskId, commentContent).subscribe({
    next:(data: AppComment) => {
      console.log('Comment created successfully:', data);
      this.comments.push(data); // Add the new comment to the local list
      this.newComment = ''; // Clear the input field
    },
    error:(error) => {
      console.error('Error creating comment:', error);
    }
  })
}}
