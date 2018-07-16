import { Injectable } from '@angular/core';
import { Http, Headers, RequestOptions } from '@angular/http';

import { AuthenticationService } from '../authentication.service';

@Injectable()
export class CursosService {

  constructor(
	  private Http: Http, 
	  private AuthenticationService: AuthenticationService
	) { }

  myList = []
  private api = 'http://localhost:3000/cursos/'

  findAll(){
  	this.Http.get(this.api)
  		.subscribe(response => {
  			this.myList = response.json();
  		})
  }
  createItem(newItem){
	  var options = new RequestOptions({
		  headers: new Headers({
			'Authorization': 'JWT ' + this.AuthenticationService.token
		  })
	  });
	  
		this.Http.post(this.api, newItem, options)
	  .subscribe(response => {
		  this.myList.push(response.json());
	  });
  }
  removeItem(item){
	  this.Http.delete(`${this.api}${item._id}`)
	  .subscribe(response => {
		  if(response.json().message === 'success'){
				var index = this.myList.indexOf(item);
				this.myList.splice(index, 1);
		  }		  
	  });
	}
}