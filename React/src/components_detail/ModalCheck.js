import React from 'react';
import './modal.scss';

const ModalCheck = (props) => {
    const { open, close, header, content, check } = props;
    return (
        <div className={open ? 'openModal modal' : 'modal'}>
            {open ? 
            (<section>
                <header>
                {header}
                    <button className="close" onClick={close}>
                        &times;
                    </button>
                </header>
                <main>{props.children}</main>
                {content}
                <footer>
                    <button className="check" onClick={check}>
                        확인
                    </button>&nbsp;&nbsp;
                    <button className="close" onClick={close}>
                        닫기
                    </button>
                </footer>
            </section>)
            : 
            null}
        </div>
    );
};

export default ModalCheck;