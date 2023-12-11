import styled, { keyframes } from 'styled-components';

const hideSlowAnimation = keyframes`
  0% {
    opacity: 1;
    transform: translateY(0);
  }
  100% {
    opacity: 0;
    transform: translateY(-20px);
  }
`;

export const Background = styled.div`
  position: fixed;
  width: 100vw;
  height: 100vh;
  top: 0;
  left: 0;
  background: whitesmoke;
  z-index: 999;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;

  animation-name: ${hideSlowAnimation};
  animation-delay: 0.6s;
  animation-duration: 1.3s;
  animation-fill-mode: forwards;
`;

export const LoadingText = styled.div`
  font: 1rem 'Noto Sans KR';
  text-align: center;
`;

