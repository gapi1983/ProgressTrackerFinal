import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { RefreshInterceptor } from './interceptor/refresh.interceptor';
import { Setup2faComponent } from './setup2fa/setup2fa.component';



@NgModule({
  declarations: [
    AppComponent,
  ],
  imports: [
    ReactiveFormsModule,
    HttpClientModule,
    BrowserModule,
    AppRoutingModule,
    BrowserAnimationsModule,
  ],
  providers: [ { provide: HTTP_INTERCEPTORS, useClass: RefreshInterceptor, multi: true }],
  bootstrap: [AppComponent]
})
export class AppModule { }
