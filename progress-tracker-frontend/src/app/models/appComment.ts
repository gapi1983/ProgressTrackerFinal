export interface AppComment {
    commentId: string;  
    taskId: string;
    userId: string;
    userName: string; 
    content: string;
    createdAt: Date;
}