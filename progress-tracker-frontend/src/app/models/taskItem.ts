import { User } from "./user";

export interface TaskItem {
  taskId: string;  
  title: string;
  description: string;
  dueDate: Date;
  status: string;
  progressPercentage: number;
  assignedToUserId: string;
  createdByUserId: string;
  assignedToUser?: User;  
  createdByUser?: User;   
  comments?: Comment[];
}