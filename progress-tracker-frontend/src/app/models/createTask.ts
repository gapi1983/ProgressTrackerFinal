import { User } from "./user";

export interface createTask{
    TaskId?:string;
    title:string;
    description:string;
    dueDate:string;
    status:string;
    progressPercentage:number;
    assignedToUserId:string;

} 