import { Component, OnInit } from '@angular/core';
import { AuthenticationService } from '../authentication.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  login = {name: '', password: ''};
  isLogged = false;

  constructor(
    private AuthenticationService : AuthenticationService
  ) { }

  ngOnInit() {
  }

  log(){
    this.AuthenticationService.login(this.login, (response)=>{
      this.isLogged = response;
    });
  }
}
