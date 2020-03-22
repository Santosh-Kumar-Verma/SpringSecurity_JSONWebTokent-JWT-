package com.springsecurity.jwt.dto;

import java.io.Serializable;

public class Employee implements Serializable {
	private Long empId;
	private String name;
	
	public Employee(Long empId, String name) {
		this.empId = empId;
		this.name = name;
	}
	public Long getEmpId() {
		return empId;
	}
	public void setEmpId(Long empId) {
		this.empId = empId;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

}
