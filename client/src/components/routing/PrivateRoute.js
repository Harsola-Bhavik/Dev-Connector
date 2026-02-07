import { Navigate, Outlet } from 'react-router-dom'
import { connect } from 'react-redux'
import PropTypes from 'prop-types'

const PrivateRoute = ({ auth }) => {
  if (!auth.isAuthenticated && !auth.loading) {
    return <Navigate to="/login" />
  }

  return <Outlet />
}

PrivateRoute.propTypes = {
  auth: PropTypes.object.isRequired,
}

const mapStateToProps = (state) => ({
  auth: state.auth,
})

export default connect(mapStateToProps)(PrivateRoute)
