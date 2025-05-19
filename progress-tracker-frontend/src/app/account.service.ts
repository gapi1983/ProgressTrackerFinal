import { HttpClient, HttpClientModule } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Register } from './models/register-model';
import { environment } from 'src/environments/environment';
import { Login } from './models/login';
import { ResetPasswordDto } from './models/resetPassword';
import { ForgotPasswordDto } from './models/forgotPassword';
import { BehaviorSubject, catchError, map, Observable, of, tap } from 'rxjs';
import { CurrentUser } from './models/currentUser';
import { TwoFaCodeDto } from './models/TwoFaCodeDto';
import { LoginResponse } from './models/loginResponse';
import { Setup2FaResponse } from './models/Setup2FaResponse';
import { Login2FaRequest } from './models/login2FaRequest';



@Injectable({
  providedIn: 'root'
})
export class AccountService {



  constructor(private http:HttpClient) {

    this.checkAuthStatus(); // when service is created check if user is authenticated or not
    
   }

   currentUser?: CurrentUser; 

  baseUrl = 'https://localhost:7225/api/Auth'; // change to use  this api in all of my services 
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(false); // this will track if user authenticated or not
  public isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  register(model:Register){
    return this.http.post(`https://localhost:7225/api/Auth/register`,model);
  }

  login(model: Login): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.baseUrl}/login`,model,{ withCredentials: true }    // ← this is correct and required
    ).pipe(
      tap(res => {
        if (!res.requires2FA) {
          // you might also mark your isAuthenticatedSubject here
          this.isAuthenticatedSubject.next(true);
        }
      })
    );
  }
  logout(){
    return this.http.post(`https://localhost:7225/api/Auth/logout`,{}, {withCredentials:true}).pipe(
      tap(()=>this.isAuthenticatedSubject.next(false))); // when user logout set the value of isAuthenticatedSubject to false
  }
  isLoggedIn(): Observable<boolean> {
    return this.isAuthenticatedSubject.asObservable();
  }
  resetPassword(model:ResetPasswordDto){
    return this.http.post(`${this.baseUrl}/reset-password`, model);
  }
  forgotPassword(email:string){
    return this.http.post(`https://localhost:7225/api/Auth/forgot-password/${email}`,{});
  }
  confirmEmail(email:string, token:string){
    return this.http.get(`${this.baseUrl}/confirm-email?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`);
  }
  getCurrentUser(): Observable<CurrentUser> {
    return this.http.get<CurrentUser>(`https://localhost:7225/api/auth/me`, {withCredentials: true})
      .pipe(
        tap(currentUser => {
          // e.g. store it in a Subject or local property
          this.currentUser = currentUser;
        })
      );
  }

// 2FA
login2fa(request: Login2FaRequest): Observable<any> {
  return this.http.post(`${this.baseUrl}/login/2fa`,request,{ withCredentials: true }
  );
}
// fetch the QR code for 2FA setup
get2FaSetup(): Observable<Setup2FaResponse> {
  return this.http.get<Setup2FaResponse>(`${this.baseUrl}/2fa/setup`,{ withCredentials: true }
  );
}
// confirm code
enable2fa(code: string): Observable<any> {
  return this.http.post(`${this.baseUrl}/2fa/enable`,{ code },{ withCredentials: true }
  );
}

// method to verify with backend if user is authenticated or not
checkAuthStatus(): Observable<boolean> {
  return this.http.get<{ isLoggedIn: boolean }>(`${this.baseUrl}/verify`, { withCredentials: true })
    .pipe(
      map(response => {
        this.isAuthenticatedSubject.next(response.isLoggedIn);
        return response.isLoggedIn;
      }),
      catchError(err => {
        this.isAuthenticatedSubject.next(false);
        return of(false);
      })
    );
}

 refresh():Observable<boolean>{
  return this.http.post(`${this.baseUrl}/refresh`,{}, {withCredentials:true}).pipe(map(()=>true))
 }

   // reset 2fa
   reset2Fa(userId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/2fa/reset/${userId}`,{ withCredentials: true }
    );
  }
}
