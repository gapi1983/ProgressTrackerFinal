import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { CreateComment } from './models/createComment';
import { Observable } from 'rxjs';
import { AppComment } from './models/appComment';

@Injectable({
  providedIn: 'root'
})
export class CommentService {


  constructor(private http:HttpClient) { }
  
    baseUrl = 'https://localhost:7225/api/tasks';
  
    createComment(taskId:string, comment:CreateComment):Observable<AppComment>{
      return this.http.post<AppComment>(`${this.baseUrl}/${taskId}/comments`,comment,{withCredentials:true});
    }

    deleteComment(taskId:string, commentId:string):Observable<void>{
      return this.http.delete<void>(`${this.baseUrl}/${taskId}/comments/${commentId}`,{withCredentials:true});
    }

    getCommentsForTask(taskId:string):Observable<AppComment[]>{
      return this.http.get<AppComment[]>(`${this.baseUrl}/${taskId}/comments`,{withCredentials:true});
    }


}
