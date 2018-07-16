import { Component, OnInit } from '@angular/core';

import { CursosService } from '../cursos.service';

@Component({
  selector: 'app-my-list',
  templateUrl: './my-list.component.html',
  styleUrls: ['./my-list.component.css']
})

export class MyListComponent implements OnInit {

  constructor(	 
     private CursosService: CursosService
  ) {}

  ngOnInit() {
    this.CursosService.findAll();
  }

  get myList(){
	  return this.CursosService.myList;
  }

  removeItem(item){
	  this.CursosService.removeItem(item);
  }

}