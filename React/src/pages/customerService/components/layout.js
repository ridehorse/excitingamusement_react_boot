import { Outlet } from 'react-router-dom';

import CustomerMove from '../customerMove.js';

const Layout = () => {
    return (
        <div>
            <CustomerMove />
            <main>
                <Outlet />
            </main>
        </div>
    );
};

export default Layout;