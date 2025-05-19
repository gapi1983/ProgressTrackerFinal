import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { ConfirmAccountComponent } from './confirm-account.component';

const routes: Routes = [
  { path: '', component: ConfirmAccountComponent }, // Default route for this module
];

@NgModule({
  declarations: [ConfirmAccountComponent],
  imports: [
    CommonModule,
    RouterModule.forChild(routes)
  ]
})
export class ConfirmAccountModule { }
