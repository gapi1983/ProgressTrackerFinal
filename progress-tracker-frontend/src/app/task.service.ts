import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { User } from './models/user';
import { createTask } from './models/createTask';
import { TaskItem } from './models/taskItem';
import { UpdateTask } from './models/updateTask';


@Injectable({
  providedIn: 'root'
})
export class TaskService {

  constructor(private http:HttpClient) { }

  baseUrl = 'https://localhost:7225/api/task';

  createTask(createTaskDto:createTask):Observable<TaskItem>{
    return this.http.post<TaskItem>(`${this.baseUrl}/create-task`,createTaskDto,{withCredentials:true});
  }
  getAllTasks():Observable<TaskItem[]>{
    return this.http.get<TaskItem[]>(`${this.baseUrl}/get-all-tasks`,{withCredentials:true});
  }
  updateTask(taskId: string, task: UpdateTask): Observable<any> {
    return this.http.put(`${this.baseUrl}/${taskId}`, task, { withCredentials: true });
  }
  getMyTasks():Observable<TaskItem[]>{
    return this.http.get<TaskItem[]>(`${this.baseUrl}/my-tasks`,{withCredentials:true});
  }
  deleteTask(taskId: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/${taskId}`, { withCredentials: true });
  }
  
}
