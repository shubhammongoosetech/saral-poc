import React from 'react';
import { AuthLayout } from '@/app/layouts/AuthLayout';
import { LoginForm } from './LoginForm';

export const Login: React.FC = () => {
  return (
    <AuthLayout>
      <LoginForm />
    </AuthLayout>
  );
};

export default Login;
