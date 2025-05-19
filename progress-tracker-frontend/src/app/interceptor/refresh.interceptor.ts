import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { Observable,  throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, switchMap, take, tap } from 'rxjs/operators';
import { AccountService } from '../account.service';

@Injectable()
export class RefreshInterceptor implements HttpInterceptor {

  private refreshing = false;
  private refreshDone$ = new BehaviorSubject<boolean>(false);

  constructor(private account:AccountService) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    //send cookies
    const authRequest = request.clone({withCredentials:true});

    return next.handle(authRequest).pipe(
      catchError(err => {
        // only try refresh on 401/403 from our API
        if (err instanceof HttpErrorResponse && (err.status === 401 || err.status === 403)) {
          return this.handleRefresh(authRequest, next);
        }
        return throwError(() => err);
      })
    );
  }
  private handleRefresh(origReq: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!this.refreshing) {
      // start a single refresh call
      this.refreshing = true;
      this.refreshDone$.next(false);

      return this.account.refresh().pipe(
        tap(() => {
          this.refreshing = false;
          this.refreshDone$.next(true);       
        }),
        switchMap(() => next.handle(origReq)), 
        catchError(err => {                    
          this.refreshing = false;
          this.refreshDone$.next(true);
          return throwError(() => err);
        })
      );
    }

    // if a refresh is already running, queue until it's done
    return this.refreshDone$.pipe(
      filter(done => done),
      take(1),
      switchMap(() => next.handle(origReq))
    );
  }
}


