/*
SQLyog Ultimate v12.09 (64 bit)
MySQL - 8.0.28 
*********************************************************************
*/
/*!40101 SET NAMES utf8 */;

create table `user` (
	`id` int (11),
	`username` varchar (765),
	`password` varchar (765),
	`permission` varchar (765),
	`role` varchar (765)
); 
insert into `user` (`id`, `username`, `password`, `permission`, `role`) values('1','user1','$2a$10$0iIqBH8tvt7MnUrCE7Ihi.YAcFd26RLIL0jtjufaT.jbdcXn9xoq.','','ROLE_ADMIN');
insert into `user` (`id`, `username`, `password`, `permission`, `role`) values('2','user2','$2a$10$Qqlhl3ah.CUBsERrO7CBru3HAXNQFqUCyxJngeunsRlGh6NnNvhWa','job:add','ROLE_USER');
insert into `user` (`id`, `username`, `password`, `permission`, `role`) values('3','user3','$2a$10$TGBwYr/UDUWJaD989VhMIOrDGiqySJ.S8ehtENKMOi5hGaBlOfcmO',NULL,NULL);
