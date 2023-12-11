import { MoonLoader } from 'react-spinners';
import { Background, LoadingText } from './LoadingStyle';

const Loading = () => {

    return (
        <Background>
            <LoadingText>잠시만 기다려주세요</LoadingText>
            <MoonLoader
                color="rgba(19, 37, 195, 1)"
                cssOverride={{}}
                loading
                size={40}
                speedMultiplier={0.8}
            />
        </Background>
    );
};

export default Loading;