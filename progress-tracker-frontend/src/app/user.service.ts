import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, tap } from 'rxjs';
import { User } from './models/user';
import { UpdateUser } from './models/updateUser';
import { Role } from './models/role';
import { createTask } from './models/createTask';
import { TaskItem } from './models/taskItem';
import { CurrentUser } from './models/currentUser';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  constructor(private http:HttpClient) { }

  private userRole!:string;
  private username!:string;
  baseUrl = 'https://localhost:7225/api/user';

  getUsers():Observable<User[]>{
    return this.http.get<User[]>(`${this.baseUrl}/all-users`,{withCredentials:true});
  }
  getUserByEmail(email:string):Observable<User>{
    return this.http.get<User>(`${this.baseUrl}/user-by-email/${email}`,{withCredentials:true});
  }
  deleteUsers(id:number){
    return this.http.delete(`${this.baseUrl}/delete-user/${id}`,{withCredentials:true});
  }
  updateUser(id: string, user: UpdateUser): Observable<any> {
    return this.http.put(`${this.baseUrl}/update-user/${id}`, user, { withCredentials: true });
  }

  // role endpoints
  addUserRole(id:string, roleName:string){
    return this.http.post(`${this.baseUrl}/add-user-role/${id}/${roleName}`,null,{withCredentials:true});
  };

  removeUserRole(id:string, roleName:string){
    return this.http.delete(`${this.baseUrl}/remove-user-role/${id}/${roleName}`,{ withCredentials: true }
    );
  };
  getAllRoles():Observable<Role[]>{
    return this.http.get<Role[]>(`${this.baseUrl}/all-roles`,{withCredentials:true});
  }
  getUsersByRole(roleId:string):Observable<User[]>{
    return this.http.get<User[]>( `${this.baseUrl}/users-by-role/${roleId}`,{withCredentials:true});

  }
  addRoleToUser(userId:string, roleName:string){
    return this.http.post(`${this.baseUrl}/add-user-role/${userId}/${roleName}`,null,{withCredentials:true});
  }
  removeRoleFromUser(userId:string, roleName:string){
    return this.http.delete(`${this.baseUrl}/remove-user-role/${userId}/${roleName}`,{withCredentials:true});
  }

  // task endpoints
  createTask(createTaskDto:createTask):Observable<TaskItem>{
    return this.http.post<TaskItem>(`${this.baseUrl}/create-task`,createTaskDto,{withCredentials:true});
  }


  
}
