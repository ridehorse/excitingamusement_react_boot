// import React, { useEffect, useLayoutEffect, useState } from 'react';
// import './modal.scss';

// import io from 'socket.io-client';

// function ShowChatList(props){

//     const {chatList, member_id, user} = props;

//     return (
//     // <div>
//     //     <ul>
//     //     {chatList && chatList.map((msg, index) => {
//     //         member_id === user ?
//     //         (<li key={index} style={{textAlign:'right'}}>
//     //             {member_id} : {msg}
//     //         </li>)
//     //         :
//     //         (<li key={index} style={{textAlign:'right'}}>
//     //             {user} : {msg}
//     //         </li>)
//     //     })}
//     //     </ul>
//     // </div>

//     <ul>
//         {chatList && chatList.map((msg, index) => (
//             <li key={index} style={{textAlign:'right'}}>
//                 {member_id} : {msg}
//             </li>
//         ))}
//     </ul>

//     );
// }

// const ENDPOINT = 'http://localhost:5000';

// let socket;

// const ModalChat = (props) => {
//     const { open, close, header, member_id, socket } = props;

//     const [message, setMessage] = useState('');
//     const [chatList, setChatList] = useState([])
//     const [user, setUser] = useState(null);
//     const [receivedMessages, setReceivedMessages] = useState(null);

//     useEffect(() => {
//         const socket = io('http://localhost:5000', {
//             cors: {
//                 origin: "*",
//             }
// 	    });
//     },[]);

//     useEffect(() => {
//         socket = io(ENDPOINT);
//     }, [ENDPOINT]);

//     useEffect(() => {
//         receivedMessages && setChatList((prev) => [...prev, receivedMessages]);
//     },[receivedMessages])
    
//     useEffect(() => {
//         socket.on('test', data => {
//             setReceivedMessages(data.message);
//             setUser(data.member_id);
//         });
//     },[socket])
    
// 	const sendMessage = e => {
//         e.preventDefault();
        
//         //소켓 서버로 데이터 전송
// 		socket.emit("test", {
// 			member_id: member_id, message: message
// 		});

//         setMessage("");
//         e.target.value = "";
// 	}

//     return (
//         <div className={open ? 'openModal modal' : 'modal'}>    
//             {open ? 
//             (
//             <section style={{position:'relative'}}>
//                 <header>
//                     <h4>{header}</h4>
//                     <button className="close" onClick={close}>
//                         X
//                     </button>
//                 </header>
//                 <main style={{position:'relative', height:'300px', width:'100%'}}>
//                     <ShowChatList 
//                         chatList={chatList} 
//                         member_id={member_id} 
//                         user={user}
//                     />
//                 </main>
//                 <footer>
//                     <form onSubmit={sendMessage}>
//                         <textarea
//                             type='text'
//                             cols='35'
//                             value={message}
//                             onChange={e => {setMessage(e.target.value)}}
//                         />&nbsp;
//                         <button type='submit'>전송</button>
//                     </form>
//                 </footer>
//             </section>
//             )
//             : 
//             null}
//         </div>
//     );
// };

// export default ModalChat;