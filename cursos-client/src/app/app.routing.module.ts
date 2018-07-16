import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router'

import { MyFormComponent } from './cursos/my-form/my-form.component';
import { LoginComponent } from './login/login.component';
import { AuthenticationGuard } from './authentication.guard';


const APP_ROUTES = [
    {path: 'cursos/new', component: MyFormComponent, canActivate: [AuthenticationGuard]},
    {path: 'cursos/:id', component: MyFormComponent},
    {path: 'login', component: LoginComponent}

]


@NgModule({
    imports: [RouterModule.forRoot(APP_ROUTES)],
    exports:  [RouterModule]

})

export class AppRoutingModule {}