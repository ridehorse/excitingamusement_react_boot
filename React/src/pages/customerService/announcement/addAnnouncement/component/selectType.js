import 'bootstrap/dist/css/bootstrap.min.css';
import React from 'react';

function SelectType(props) {
    const { inputRef } = props;

    const changeTitleValue = (titleEvent) => {
        inputRef.current = titleEvent.target.value;
    };

    return (
        <>
            <div className='create-window'>
                <div className="form-floating mb-3">
                    <input
                        type="text"
                        className="form-control"
                        id="flootingInput"
                        name="b_title"
                        onChange={changeTitleValue} />
                    <label htmlFor="flootingInput">제목</label>
                </div>
            </div>
        </>
    );
}

export default SelectType;