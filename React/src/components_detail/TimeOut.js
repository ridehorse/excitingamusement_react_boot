import React, { useEffect, useState } from 'react';
import { MoonLoader } from 'react-spinners';

const TimeOut = () => {

    let [alert, setAlert] = useState(true);

    useEffect(() => {
        //2초 후에 alert의 상태 값을 true => false로 변경
        let timer = setTimeout(() => {setAlert(false)}, 1300);
    },[])

    return (
        alert === true
        &&
        <MoonLoader
            color="rgba(19, 37, 195, 1)"
            cssOverride={{}}
            loading
            size={40}
            speedMultiplier={0.8}
        />
    );
};

export default TimeOut;