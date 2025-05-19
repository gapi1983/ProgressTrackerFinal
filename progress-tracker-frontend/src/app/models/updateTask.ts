export interface UpdateTask {
    title: string;
    description: string;
    dueDate: Date;
    status: string;
    progressPercentage: number;
    assignedToUserId: string;
  }