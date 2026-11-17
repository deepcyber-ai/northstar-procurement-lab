export interface TrainingUser {
  id: string;
  displayName: string;
  email: string;
  tenantId: string;
  organizationName: string;
  jobTitle: string;
  role: string;
}

export interface LoginResponse {
  token: string;
  user: TrainingUser;
  trainingOnly: boolean;
}

export interface Order {
  id: string;
  tenantId: string;
  ownerId: string;
  item: string;
  quantity: number;
  unitPrice: number;
  status: string;
  workflowStarts: number;
  version: number;
}

export interface Workflow {
  id: string;
  orderId: string;
  tenantId: string;
  requestedBy: string;
  action: string;
  status: string;
  executionNumber: number;
  createdAt: string;
}

export interface OrderListEnvelope {
  orders: Order[];
}

export interface WorkflowListEnvelope {
  workflows: Workflow[];
}

export interface DemoAccount {
  email: string;
  name: string;
  organization: string;
  role: string;
}

export interface AdminOverview {
  generatedFor: string;
  scope: string;
  trustedRoleSource: string;
  userCount: number;
  orderCount: number;
  workflowCount: number;
  totalOrderValue: number;
  trainingOnly: boolean;
}

export function organizationLabel(tenantId: string): string {
  const names: Record<string, string> = {
    'tenant-a': 'Aster & Row',
    'tenant-b': 'Beacon Works'
  };
  return names[tenantId] ?? tenantId;
}
